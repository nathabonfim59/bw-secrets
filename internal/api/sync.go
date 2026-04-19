package api

import "context"

func (c *Client) Sync(ctx context.Context) (*SyncResponse, error) {
	var result SyncResponse
	err := c.do(ctx, "GET", "/api/sync", nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
