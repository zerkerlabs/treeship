// RFC 9116 security.txt. A static file under public/.well-known/ is shadowed
// by the [[...slug]] catch-all's own generated 404 for that exact path (Next
// pre-renders it as a slug and that page wins over public/ at the same URL),
// so this is a route handler instead -- same pattern as app/llms.txt.
export const revalidate = false;

const BODY = `Contact: mailto:security@treeship.dev
Contact: https://github.com/zerkerlabs/treeship/security/advisories/new
Expires: 2027-09-27T00:00:00.000Z
Preferred-Languages: en
Canonical: https://docs.treeship.dev/.well-known/security.txt
Policy: https://github.com/zerkerlabs/treeship/blob/main/SECURITY.md
Acknowledgments: https://github.com/zerkerlabs/treeship/security/advisories
`;

export function GET() {
  return new Response(BODY, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
}
