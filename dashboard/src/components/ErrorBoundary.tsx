// App-level error boundary. A thrown render error during a live demo must never
// white-screen the whole app — this catches it, shows a recoverable panel, and
// lets the user reset back into the dashboard.
import { Component, type ErrorInfo, type ReactNode } from "react";
import { Icon } from "./icons";

interface Props {
  children: ReactNode;
  /** Changing this value (e.g. the route) clears a previous error. */
  resetKey?: unknown;
}
interface State {
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidUpdate(prev: Props) {
    // Auto-recover when the user navigates to a different route.
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surfaced to the console for debugging; never crashes the shell.
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="card p-8 text-center max-w-lg mx-auto mt-10 animate-fade-in">
          <div className="grid place-items-center w-12 h-12 rounded-xl bg-sev-critical/15 text-sev-critical mx-auto mb-3">
            <Icon name="alert" size={24} />
          </div>
          <h2 className="text-base font-semibold text-slate-100">This view hit an error</h2>
          <p className="text-sm text-slate-400 mt-1">
            The rest of the platform is unaffected. Reset the view or switch pages to continue.
          </p>
          <pre className="text-[11px] text-slate-500 mt-3 max-h-32 overflow-auto text-left bg-black/30 rounded-lg p-2">
            {String(this.state.error?.message || this.state.error)}
          </pre>
          <button className="btn mt-4" onClick={() => this.setState({ error: null })}>
            <Icon name="refresh" size={14} /> Reset view
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
