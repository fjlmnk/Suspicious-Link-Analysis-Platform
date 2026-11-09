import { useState, type FormEvent } from 'react';
import { Shield, Loader2 } from 'lucide-react';

interface URLInputProps {
  onSubmit: (url: string) => void | Promise<void>;
  loading?: boolean;
}

function isValidUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export default function URLInput({ onSubmit, loading = false }: URLInputProps) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    const trimmed = url.trim();
    if (!trimmed) {
      setError('Please enter a URL to analyze.');
      return;
    }

    // Auto-prepend https:// if no protocol
    let normalizedUrl = trimmed;
    if (!/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = `https://${normalizedUrl}`;
    }

    if (!isValidUrl(normalizedUrl)) {
      setError('Please enter a valid URL (e.g., https://example.com).');
      return;
    }

    setUrl(normalizedUrl);
    await onSubmit(normalizedUrl);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto">
      <div className="relative">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (error) setError('');
              }}
              placeholder="Enter URL to analyze..."
              disabled={loading}
              className="input-field pl-4 pr-4 py-4 text-base sm:text-lg"
              autoFocus
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="btn-primary flex items-center gap-2 px-6 sm:px-8 py-4 text-base whitespace-nowrap"
          >
            {loading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                <span className="hidden sm:inline">Analyzing...</span>
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                <span className="hidden sm:inline">Analyze URL</span>
              </>
            )}
          </button>
        </div>
      </div>
      {error && (
        <p className="mt-2 text-sm text-red-400 flex items-center gap-1.5">
          <span className="inline-block w-1 h-1 rounded-full bg-red-400" />
          {error}
        </p>
      )}
    </form>
  );
}
