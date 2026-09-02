"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { Button, Card, Input, Label } from "@/components/ui/primitives";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { session, loading, login, signup, error } = useAuth();
  const router = useRouter();

  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("admin@opspilot.dev");
  const [password, setPassword] = useState("opspilot");
  const [organization, setOrganization] = useState("");
  const [fullName, setFullName] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!loading && session) router.replace("/dashboard");
  }, [session, loading, router]);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await signup({
          organization_name: organization,
          email,
          password,
          full_name: fullName,
        });
      }
    } catch {
      /* the error is surfaced through the auth context */
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-sky-600/15 text-xl ring-1 ring-sky-500/30">
            🛰️
          </div>
          <h1 className="text-xl font-semibold tracking-tight">OpsPilot AI</h1>
          <p className="mt-1 text-xs text-[--color-text-muted]">
            Autonomous incident response, with a human on every risky change.
          </p>
        </div>

        <Card className="p-6">
          <div className="mb-5 flex rounded-lg bg-[--color-canvas] p-1">
            {(["login", "signup"] as const).map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => setMode(value)}
                className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  mode === value
                    ? "bg-[--color-surface-raised] text-[--color-text-primary]"
                    : "text-[--color-text-muted] hover:text-[--color-text-secondary]"
                }`}
              >
                {value === "login" ? "Sign in" : "Create organisation"}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === "signup" ? (
              <>
                <div>
                  <Label htmlFor="organization">Organisation name</Label>
                  <Input
                    id="organization"
                    required
                    minLength={2}
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    placeholder="Acme Corp"
                  />
                </div>
                <div>
                  <Label htmlFor="fullName">Your name</Label>
                  <Input
                    id="fullName"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Ada Lovelace"
                  />
                </div>
              </>
            ) : null}

            <div>
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <div>
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                required
                minLength={8}
                autoComplete={
                  mode === "login" ? "current-password" : "new-password"
                }
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            {error ? (
              <p className="rounded-lg bg-red-500/10 px-3 py-2 text-xs text-red-300 ring-1 ring-inset ring-red-500/25">
                {error}
              </p>
            ) : null}

            <Button
              type="submit"
              variant="primary"
              className="w-full"
              loading={submitting}
            >
              {mode === "login" ? "Sign in" : "Create organisation"}
            </Button>
          </form>

          {mode === "login" ? (
            <p className="mt-4 text-center text-[11px] text-[--color-text-muted]">
              Demo seed: <code className="font-mono">admin@opspilot.dev</code> /{" "}
              <code className="font-mono">opspilot</code>
            </p>
          ) : null}
        </Card>
      </div>
    </main>
  );
}
