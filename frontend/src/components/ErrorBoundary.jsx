import React, { Component } from 'react';
import { AlertOctagon } from 'lucide-react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI.
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("[ERROR ISOLATOR] Caught isolated component exception:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="border border-rose-500/20 bg-rose-500/5 p-6 rounded-xl flex flex-col items-center justify-center text-center space-y-3 font-mono min-h-[160px] h-full shadow-lg">
          <div className="p-2 bg-rose-500/10 rounded-full text-rose-400 animate-pulse">
            <AlertOctagon className="w-6 h-6" />
          </div>
          <div>
            <h4 className="text-xs font-bold text-rose-400 uppercase tracking-widest">[FAULT SEPARATION] Component Unavailable</h4>
            <p className="text-[9px] text-slate-500 uppercase mt-1">
              Error Isolated successfully // Platform Remains operational
            </p>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
