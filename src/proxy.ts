import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // Check if the user is hitting any protected dashboard path
    if (pathname.startsWith('/dashboard')) {
        const authCookie = request.cookies.get('kpmg_auth_user')?.value;

        if (!authCookie) {
            // Not logged in at all
            return NextResponse.redirect(new URL('/login', request.url));
        }

        try {
            const user = JSON.parse(authCookie);

            // Enterprise RBAC: Ensure strict control over the Admin domain
            if (pathname.startsWith('/dashboard/admin')) {
                if (user.role !== 'admin') {
                    // Non-admin attempting to access root admin zone
                    return NextResponse.redirect(new URL('/unauthorized', request.url));
                }
            }

            // Note: Similarly, we could enforce that `business-user` cannot access `/dashboard/developer`.
            // For now, let's keep the core focus on protecting the `admin` area.
            if (pathname.startsWith('/dashboard/developer') && user.role !== 'developer' && user.role !== 'admin') {
                return NextResponse.redirect(new URL('/unauthorized', request.url));
            }

            if (pathname.startsWith('/dashboard/analyst') && user.role !== 'analyst' && user.role !== 'admin') {
                return NextResponse.redirect(new URL('/unauthorized', request.url));
            }

        } catch (e) {
            // Invalid cookie payload
            return NextResponse.redirect(new URL('/login', request.url));
        }
    }

    return NextResponse.next();
}

export const config = {
    matcher: ['/dashboard/:path*'],
};
