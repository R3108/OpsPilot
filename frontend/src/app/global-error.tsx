"use client";

import { useEffect } from "react";

import { Button, Card } from "@/components/ui/primitives";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("global-error", error);
  }, [error]);

  return (
    <html lang="en">
      <body>
        <main className="flex min-h-screen items-center justify-center px-4">
          <Card className="max-w-sm p-6 text-center">
            <h1 className="text-lg font-semibold">Something went wrong</h1>
            <p className="mt-2 text-sm text-[--color-text-muted]">
              The app hit an unexpected error. Trying again usually fixes it.
            </p>
            <Button variant="primary" className="mt-4" onClick={() => reset()}>
              Try again
            </Button>
          </Card>
        </main>
      </body>
    </html>
  );
}
