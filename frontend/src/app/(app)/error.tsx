"use client";

import { Button, Card, EmptyState } from "@/components/ui/primitives";

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="p-5 lg:p-8">
      <Card className="p-6">
        <EmptyState
          icon="⚠️"
          title="This page failed to load"
          description={error.message || "An unexpected render error occurred."}
        />
        <div className="mt-4 flex justify-center">
          <Button variant="primary" onClick={() => reset()}>
            Try again
          </Button>
        </div>
      </Card>
    </div>
  );
}
