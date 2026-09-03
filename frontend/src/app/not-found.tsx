import Link from "next/link";

import { Button, Card, EmptyState } from "@/components/ui/primitives";

export default function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <Card className="max-w-sm p-6 text-center">
        <EmptyState
          icon="🔍"
          title="Page not found"
          description="The page you asked for does not exist or was moved."
        />
        <div className="mt-4 flex justify-center">
          <Link href="/dashboard">
            <Button variant="primary">Back to dashboard</Button>
          </Link>
        </div>
      </Card>
    </div>
  );
}
