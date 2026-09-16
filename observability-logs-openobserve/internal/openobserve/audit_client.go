// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package openobserve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

// DefaultAuditStream is the audit stream used unless configured otherwise.
const DefaultAuditStream = "audit_logs"

// WithAuditStream sets the stream audit records are read from.
func (c *Client) WithAuditStream(stream string) *Client {
	c.auditStream = stream
	return c
}

// streamColumns returns the columns a stream has stored so far. OpenObserve adds a column
// only when a record first carries the field.
func (c *Client) streamColumns(ctx context.Context, stream string) (map[string]bool, error) {
	endpoint := fmt.Sprintf("%s/api/%s/streams/%s/schema?type=logs",
		c.baseURL, url.PathEscape(c.org), url.PathEscape(stream))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(c.user, c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch stream schema: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read stream schema: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return map[string]bool{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openobserve returned status %d for stream schema: %s", resp.StatusCode, string(body))
	}

	var parsed struct {
		Schema []struct {
			Name string `json:"name"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse stream schema: %w", err)
	}

	columns := make(map[string]bool, len(parsed.Schema))
	for _, field := range parsed.Schema {
		columns[field.Name] = true
	}
	return columns, nil
}

// GetAuditLogs returns a page of audit records, their total and, when timelineInterval
// is set, the timeline.
func (c *Client) GetAuditLogs(
	ctx context.Context, params AuditLogsParams, timelineInterval string,
) (*AuditLogsResult, error) {
	columns, err := c.streamColumns(ctx, c.auditStream)
	if err != nil {
		return nil, err
	}

	conditions, ok := auditConditions(params, columns)
	if !ok || !columns[colLog] {
		return c.emptyAuditLogs(params, timelineInterval)
	}

	queryJSON, err := generateAuditLogsQuery(params, c.auditStream, conditions, c.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit logs query: %w", err)
	}
	resp, err := c.executeSearchQuery(ctx, queryJSON)
	if err != nil {
		return nil, err
	}

	records := make([]AuditRecord, 0, len(resp.Hits))
	for _, hit := range resp.Hits {
		record, err := ParseAuditRecord(hit)
		if err != nil {
			c.logger.Warn("Skipping malformed audit record", slog.Any("error", err))
			continue
		}
		records = append(records, record)
	}

	countJSON, err := generateAuditLogsCountQuery(params, c.auditStream, conditions, c.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit logs count query: %w", err)
	}
	countResp, err := c.executeSearchQuery(ctx, countJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to execute audit logs count query: %w", err)
	}

	result := &AuditLogsResult{
		Records: records,
		Total:   int64(extractTotalCount(countResp)),
		Took:    resp.Took,
	}

	if timelineInterval != "" && columns[colResult] {
		// The contract allows omitting a failed timeline rather than failing the query.
		timeline, err := c.getAuditTimeline(ctx, params, conditions, timelineInterval)
		if err != nil {
			c.logger.Warn("Failed to compute audit timeline", slog.Any("error", err))
		} else {
			result.Timeline = timeline
		}
	} else if timelineInterval != "" {
		result.Timeline, _ = buildAuditTimeline(timelineInterval, params.StartTime, params.EndTime, nil)
	}

	return result, nil
}

func (c *Client) emptyAuditLogs(params AuditLogsParams, timelineInterval string) (*AuditLogsResult, error) {
	result := &AuditLogsResult{Records: []AuditRecord{}}
	if timelineInterval != "" {
		timeline, err := buildAuditTimeline(timelineInterval, params.StartTime, params.EndTime, nil)
		if err != nil {
			return nil, err
		}
		result.Timeline = timeline
	}
	return result, nil
}

func (c *Client) getAuditTimeline(
	ctx context.Context, params AuditLogsParams, conditions []string, interval string,
) (*AuditTimeline, error) {
	width, err := parseTimelineInterval(interval)
	if err != nil {
		return nil, err
	}

	queryJSON, err := generateAuditTimelineQuery(params, c.auditStream, conditions, width, c.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit timeline query: %w", err)
	}
	resp, err := c.executeSearchQuery(ctx, queryJSON)
	if err != nil {
		return nil, err
	}

	return buildAuditTimeline(interval, params.StartTime, params.EndTime, resp.Hits)
}

// GetAuditLogFilterValues lists the distinct values a filter takes. params must already
// exclude the filter's own selections.
func (c *Client) GetAuditLogFilterValues(
	ctx context.Context, params AuditLogsParams, filter, valueSearch string, maxValues int,
) (*AuditFilterValues, error) {
	columns, err := c.streamColumns(ctx, c.auditStream)
	if err != nil {
		return nil, err
	}

	empty := &AuditFilterValues{Values: []AuditFilterValue{}}

	conditions, ok := auditConditions(params, columns)
	if !ok {
		return empty, nil
	}
	source, ok := auditValuesSource(c.auditStream, filter, conditions, columns)
	if !ok {
		return empty, nil
	}

	queryJSON, err := generateAuditFilterValuesQuery(params, source, valueSearch, maxValues, c.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit filter values query: %w", err)
	}
	resp, err := c.executeSearchQuery(ctx, queryJSON)
	if err != nil {
		return nil, err
	}

	totalJSON, err := generateAuditFilterValuesTotalQuery(params, source, valueSearch, c.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit filter values total query: %w", err)
	}
	totalResp, err := c.executeSearchQuery(ctx, totalJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to execute audit filter values total query: %w", err)
	}

	return &AuditFilterValues{
		Values:      parseAuditFilterValues(resp),
		TotalValues: int64(extractTotalCount(totalResp)),
		Took:        resp.Took,
	}, nil
}
