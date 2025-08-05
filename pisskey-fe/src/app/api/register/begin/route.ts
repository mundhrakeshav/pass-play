import { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const username = searchParams.get('username');
  
  if (!username) {
    return Response.json({ error: 'Username required' }, { status: 400 });
  }

  try {
    const backendUrl = 'http://192.168.29.216:8080';
    const response = await fetch(`${backendUrl}/register/begin?username=${encodeURIComponent(username)}`);
    const data = await response.json();
    
    return Response.json(data, { status: response.status });
  } catch (error) {
    console.error('Proxy error:', error);
    return Response.json({ error: 'Backend connection failed' }, { status: 500 });
  }
}