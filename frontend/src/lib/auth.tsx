"use client";

import { useRouter } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { ApiError, api, tokens } from "./api";
import type { Session, UserRole } from "./types";

const ROLE_RANK: Record<UserRole, number> = {
  viewer: 0,
  responder: 10,
  approver: 20,
  admin: 30,
  owner: 40,
};

interface AuthState {
  session: Session | null;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  signup: (input: {
    organization_name: string;
    email: string;
    password: string;
    full_name?: string;
  }) => Promise<void>;
  logout: () => void;
  /** True when the signed-in user is at least `role`. */
  can: (role: UserRole) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadSession = useCallback(async () => {
    if (!tokens.access()) {
      setSession(null);
      setLoading(false);
      return;
    }
    try {
      setSession(await api.session());
    } catch (err) {
      if (err instanceof ApiError && err.isAuthError) tokens.clear();
      setSession(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // One-shot session restore on mount.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadSession();
  }, [loadSession]);

  const login = useCallback(
    async (email: string, password: string) => {
      setError(null);
      try {
        tokens.set(await api.login({ email, password }));
        setSession(await api.session());
        router.push("/dashboard");
      } catch (err) {
        const message =
          err instanceof ApiError ? err.message : "Could not sign in";
        setError(message);
        throw err;
      }
    },
    [router],
  );

  const signup = useCallback<AuthState["signup"]>(
    async (input) => {
      setError(null);
      try {
        tokens.set(await api.signup(input));
        setSession(await api.session());
        router.push("/dashboard");
      } catch (err) {
        const message =
          err instanceof ApiError ? err.message : "Could not create the account";
        setError(message);
        throw err;
      }
    },
    [router],
  );

  const logout = useCallback(() => {
    tokens.clear();
    setSession(null);
    router.push("/login");
  }, [router]);

  const can = useCallback(
    (role: UserRole) =>
      session ? ROLE_RANK[session.user.role] >= ROLE_RANK[role] : false,
    [session],
  );

  const value = useMemo(
    () => ({ session, loading, error, login, signup, logout, can }),
    [session, loading, error, login, signup, logout, can],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}

/** Redirects to /login once we know there is no session. */
export function useRequireAuth() {
  const { session, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !session) router.replace("/login");
  }, [loading, session, router]);

  return { session, loading };
}
