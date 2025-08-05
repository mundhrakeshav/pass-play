import { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    const backendUrl = 'http://192.168.29.216:8080';
    const response = await fetch(`${backendUrl}/login/discoverable/begin`);
    const data = await response.json();
    
    return Response.json(data, { status: response.status });
  } catch (error) {
    console.error('Proxy error:', error);
    return Response.json({ error: 'Backend connection failed' }, { status: 500 });
  }
}