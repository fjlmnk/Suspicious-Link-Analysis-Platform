import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="max-w-md mx-auto px-4 py-24 text-center space-y-4">
      <ShieldAlert className="w-16 h-16 text-rose-500 mx-auto" />
      <h1 className="text-4xl font-extrabold text-white">404</h1>
      <h2 className="text-xl font-bold text-slate-200">Page Not Found</h2>
      <p className="text-sm text-slate-400">
        The requested security route does not exist or has been relocated.
      </p>
      <Link
        to="/"
        className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold transition"
      >
        <ArrowLeft className="w-4 h-4" /> Return to Dashboard
      </Link>
    </div>
  );
}
