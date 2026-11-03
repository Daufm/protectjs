import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { app } from '../../apps/playground/src/index.js';

describe('playground integration', () => {
  it('exposes a health endpoint outside protection', async () => {
    const response = await request(app).get('/health');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok' });
    expect(response.headers['x-ethioshield-action']).toBeUndefined();
  });

  it('adds an EthioShield action header to application requests', async () => {
    const response = await request(app).get('/');

    expect(response.status).toBe(200);
    expect(response.headers['x-ethioshield-action']).toBe('allow');
  });
});
