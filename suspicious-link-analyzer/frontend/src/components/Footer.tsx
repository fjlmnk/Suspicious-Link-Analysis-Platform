import { Shield } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="border-t border-slate-800 bg-slate-900/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-slate-500">
            <Shield className="w-4 h-4" />
            <span className="text-sm">
              &copy; {new Date().getFullYear()} Suspicious Link Analyzer. All rights reserved.
            </span>
          </div>
          <p className="text-xs text-slate-600 text-center sm:text-right max-w-md">
            Disclaimer: This tool provides URL analysis based on third-party security providers.
            Results are informational and should not be the sole basis for security decisions.
          </p>
        </div>
      </div>
    </footer>
  );
}
