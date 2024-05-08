package exoscale

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/libdns/libdns"
)

// Client is an abstraction of Egoscale Client
type Client struct {
	egoscaleClient *egoscale.Client
	mutex          sync.Mutex
}

// setupClient invokes authentication and store client to the provider instance.
func (p *Provider) setupClient() error {
	if p.client.egoscaleClient == nil {
		client, err := egoscale.NewClient(p.APIKey, p.APISecret)
		if err != nil {
			return err
		}

		p.client.egoscaleClient = client
	}

	return nil
}

func (p *Provider) getDomainId(ctx context.Context, name string) (*string, error) {
	domains, err := p.client.egoscaleClient.ListDNSDomains(ctx, p.ExoscaleZone)
	if err != nil {
		return nil, err
	}

	for _, domain := range domains {
		if *domain.UnicodeName == name {
			return domain.ID, nil
		}
	}

	return nil, fmt.Errorf("The DNS zone %s could not be found", name)
}

func libdnsToEgoscaleRecord(r *libdns.Record) egoscale.DNSDomainRecord {

	intTTL := int64(r.TTL.Seconds())

	return egoscale.DNSDomainRecord{
		ID:      &r.ID,
		Type:    &r.Type,
		Name:    &r.Name,
		Content: &r.Value,
		TTL:     &intTTL,
	}
}

func egoscaleToLibdnsRecord(r *egoscale.DNSDomainRecord) libdns.Record {

	return libdns.Record{
		ID:    *r.ID,
		Type:  *r.Type,
		Name:  *r.Name,
		Value: strings.TrimRight(strings.TrimLeft(*r.Content, "\""), "\""),
		TTL:   time.Duration(*r.TTL * int64(time.Second)),
	}
}

func (p *Provider) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return nil, err
	}

	domainId, err := p.getDomainId(ctx, zone)
	if err != nil {
		return nil, err
	}

	records, err := p.client.egoscaleClient.ListDNSDomainRecords(ctx, p.ExoscaleZone, *domainId)
	if err != nil {
		return nil, err
	}

	var libdnsRecords []libdns.Record
	for _, record := range records {
		libdnsRecords = append(libdnsRecords, egoscaleToLibdnsRecord(&record))
	}

	return libdnsRecords, nil
}

func (p *Provider) getRecordsByNameAndType(ctx context.Context, zone string, name string, t string) ([]libdns.Record, error) {
	allRecords, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	var res []libdns.Record
	for _, r := range allRecords {
		if r.Name == normalizeRecordName(name, zone) && r.Type == t {
			res = append(res, r)
		}
	}

	return res, nil
}

func (p *Provider) createRecord(ctx context.Context, zone string, libdnsRecord libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return libdns.Record{}, err
	}

	domainId, err := p.getDomainId(ctx, zone)
	if err != nil {
		return libdns.Record{}, err
	}

	libdnsRecord.Name = normalizeRecordName(libdnsRecord.Name, zone)
	record := libdnsToEgoscaleRecord(&libdnsRecord)

	createdRecord, err := p.client.egoscaleClient.CreateDNSDomainRecord(ctx, p.ExoscaleZone, *domainId, &record)
	if err != nil {
		return libdns.Record{}, err
	}

	return egoscaleToLibdnsRecord(createdRecord), nil
}

func (p *Provider) updateRecord(ctx context.Context, zone string, libdnsRecord libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return libdns.Record{}, err
	}

	domainId, err := p.getDomainId(ctx, zone)
	if err != nil {
		return libdns.Record{}, err
	}

	record := libdnsToEgoscaleRecord(&libdnsRecord)

	err = p.client.egoscaleClient.UpdateDNSDomainRecord(ctx, p.ExoscaleZone, *domainId, &record)
	if err != nil {
		return libdns.Record{}, err
	}

	return egoscaleToLibdnsRecord(&record), nil
}

func (p *Provider) deleteRecord(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return libdns.Record{}, err
	}

	domainId, err := p.getDomainId(ctx, zone)
	if err != nil {
		return libdns.Record{}, err
	}

	r := libdnsToEgoscaleRecord(&record)

	if err = p.client.egoscaleClient.DeleteDNSDomainRecord(ctx, p.ExoscaleZone, *domainId, &r); err != nil {
		return libdns.Record{}, err
	}

	return record, nil
}

// createOrUpdateRecord creates or updates a record, either by updating existing record or creating new one.
func (p *Provider) createOrUpdateRecord(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	if len(record.ID) == 0 {
		// lookup for existing records
		// if we find one, update it
		// if we find multiple, delete them and recreate the final one

		foundRecords, err := p.getRecordsByNameAndType(ctx, zone, record.Name, record.Type)
		if err != nil {
			return libdns.Record{}, err
		}

		if len(foundRecords) == 1 {
			record.ID = foundRecords[0].ID
			return p.updateRecord(ctx, zone, record)
		} else if len(foundRecords) > 1 {
			for _, r := range foundRecords {
				_, err := p.deleteRecord(ctx, zone, r)
				if err != nil {
					return libdns.Record{}, err
				}
			}
		}

		return p.createRecord(ctx, zone, record)
	}

	return p.updateRecord(ctx, zone, record)
}

// unFQDN trims any trailing "." from fqdn. Exoscale's API does not use FQDNs.
func unFQDN(fqdn string) string {
	return strings.TrimSuffix(fqdn, ".")
}

// normalizeRecordName remove absolute record name
func normalizeRecordName(recordName string, zone string) string {
	normalized := unFQDN(recordName)
	normalized = strings.TrimSuffix(normalized, unFQDN(zone))
	return unFQDN(normalized)
}
