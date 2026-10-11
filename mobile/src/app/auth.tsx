import { Redirect } from 'expo-router';
import { useSession } from '../lib/session';

// Android also delivers the custom browser callback to the router. The pending
// auth session validates/exchanges it; this route never trusts URL credentials.
export default function AuthReturn() {
  const { session } = useSession();
  return <Redirect href={session ? '/(tabs)' : '/'} />;
}
