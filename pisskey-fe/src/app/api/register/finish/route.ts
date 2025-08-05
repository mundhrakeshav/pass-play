import { NextRequest } from 'next/server';

export async function POST(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const sessionId = searchParams.get('sessionId');
  const username = searchParams.get('username');
  
  if (!sessionId || !username) {
    return Response.json({ error: 'SessionId and username required' }, { status: 400 });
  }

  try {
    const body = await request.json();
    const backendUrl = 'http://192.168.29.216:8080';
    
    const response = await fetch(`${backendUrl}/register/finish?sessionId=${encodeURIComponent(sessionId)}&username=${encodeURIComponent(username)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    
    const data = await response.json();
    return Response.json(data, { status: response.status });
  } catch (error) {
    console.error('Proxy error:', error);
    return Response.json({ error: 'Backend connection failed' }, { status: 500 });
  }
}