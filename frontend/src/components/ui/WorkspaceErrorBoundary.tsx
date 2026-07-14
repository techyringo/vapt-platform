'use client';

import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  workspace: string;
  children: ReactNode;
}

interface State {
  failed: boolean;
  incidentId: string;
}

export class WorkspaceErrorBoundary extends Component<Props, State> {
  state: State = { failed: false, incidentId: '' };

  static getDerivedStateFromError(): State {
    return { failed: true, incidentId: `ui-${Date.now().toString(36)}` };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Browser diagnostics retain the stack; scanner evidence and other
    // workspaces continue running because only this panel is replaced.
    console.error(`[workspace:${this.props.workspace}]`, error, info.componentStack);
  }

  componentDidUpdate(previous: Props) {
    if (previous.workspace !== this.props.workspace && this.state.failed) {
      this.setState({ failed: false, incidentId: '' });
    }
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <section className="workspace-failure" role="alert">
        <AlertTriangle size={22} aria-hidden="true" />
        <div>
          <h2>{this.props.workspace} panel could not render</h2>
          <p>The assessment continues in the background. Other workspaces remain available. Incident {this.state.incidentId}.</p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={() => this.setState({ failed: false, incidentId: '' })}>
          <RefreshCw size={14} aria-hidden="true" />Retry panel
        </button>
      </section>
    );
  }
}
