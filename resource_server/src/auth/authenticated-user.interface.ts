export interface AuthenticatedUser {
  sub: string;
  scope?: string;
  azp?: string;
  preferredUsername?: string;
  email?: string;
}
