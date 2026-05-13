import { Link } from "wouter";
import { AlertTriangle, Home } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex flex-col items-center justify-center bg-background text-foreground relative overflow-hidden">
      <div 
        className="absolute inset-0 z-0 opacity-10 pointer-events-none bg-cover bg-center mix-blend-screen"
        style={{ backgroundImage: `url(${import.meta.env.BASE_URL}images/cyber-bg.png)` }}
      />
      
      <div className="relative z-10 text-center space-y-6 max-w-md p-8 glass-panel rounded-3xl border-destructive/20">
        <div className="mx-auto w-20 h-20 bg-destructive/10 rounded-full flex items-center justify-center border border-destructive/20 mb-6">
          <AlertTriangle className="w-10 h-10 text-destructive" />
        </div>
        <h1 className="text-6xl font-display font-bold text-foreground">404</h1>
        <h2 className="text-xl font-semibold text-muted-foreground uppercase tracking-widest">Resource Not Found</h2>
        <p className="text-sm text-muted-foreground/80 leading-relaxed mb-8">
          The endpoint or page you are looking for has been moved, deleted, or never existed in the current system context.
        </p>
        <Link href="/">
          <Button variant="cyber" size="lg" className="w-full font-mono uppercase tracking-wider">
            <Home className="w-4 h-4 mr-2" />
            Return to Dashboard
          </Button>
        </Link>
      </div>
    </div>
  );
}
