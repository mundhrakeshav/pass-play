import { NextRequest } from 'next/server';

export async function POST(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const sessionId = searchParams.get('sessionId');
  
  if (!sessionId) {
    return Response.json({ error: 'SessionId required' }, { status: 400 });
  }

  try {
    const body = await request.text();
    
    const backendUrl = 'http://192.168.29.216:8080';
    const response = await fetch(`${backendUrl}/login/discoverable/finish?sessionId=${encodeURIComponent(sessionId)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: body,
    });
    
    const data = await response.json();
    
    return Response.json(data, { status: response.status });
  } catch (error) {
    console.error('Proxy error:', error);
    return Response.json({ error: 'Backend connection failed' }, { status: 500 });
  }
}