import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Clock3,
  ExternalLink,
  Globe2,
  History,
  LayoutDashboard,
  Link2,
  LockKeyhole,
  Mail,
  Menu,
  Moon,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sun,
  XCircle,
} from 'lucide-react';
import { MessageScanner } from './components/MessageScanner';
import { AnalysisReport } from './components/AnalysisReport';
import { DomainChecker } from './components/DomainChecker';
import { EmergencyGuide } from './components/EmergencyGuide';
import { ScanHistoryView } from './components/ScanHistoryView';
import { AnalysisResult } from './types';
import { clearScanHistory, getScanHistory, saveScanToHistory } from './utils/storage';

type PublicPage = 'scanner' | 'links' | 'history' | 'emergency';
type AdminPage = 'admin' | 'mail';
type Page = PublicPage | AdminPage | 'gateway';
type GatewayState = 'checking' | 'caution' | 'blocked' | 'safe';

const navPublic = [
  { id: 'scanner' as const, label: 'Message scanner', icon: ShieldAlert },
  { id: 'links' as const, label: 'URL checker', icon: Globe2 },
  { id: 'history' as const, label: 'Scan history', icon: History },
  { id: 'emergency' as const, label: 'Emergency guidance', icon: CircleHelp },
];

const navAdmin = [
  { id: 'admin' as const, label: 'Overview', icon: LayoutDashboard },
  { id: 'mail' as const, label: 'Mail activity', icon: Mail },
];

const statCards = [
  { label: 'Inspected links', value: '1,284', trend: '+12.8%', icon: Link2, tone: 'blue' },
  { label: 'Threats blocked', value: '86', trend: '+8 this week', icon: ShieldAlert, tone: 'red' },
  { label: 'Needs review', value: '14', trend: '3 high priority', icon: Clock3, tone: 'amber' },
  { label: 'Mail events', value: '342', trend: 'Last 30 days', icon: Mail, tone: 'violet' },
];

function StatusPill({ status }: { status: 'blocked' | 'caution' | 'safe' | 'checking' }) {
  const styles = {
    blocked: 'status-pill status-pill-danger',
    caution: 'status-pill status-pill-warning',
    safe: 'status-pill status-pill-safe',
    checking: 'status-pill status-pill-neutral',
  };
  const labels = { blocked: 'Blocked', caution: 'Caution', safe: 'Safe', checking: 'Checking' };
  return <span className={styles[status]}>{labels[status]}</span>;
}

function App() {
  const [page, setPage] = useState<Page>('scanner');
  const [currentAnalysis, setCurrentAnalysis] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<AnalysisResult[]>([]);
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [selectedUrl, setSelectedUrl] = useState('');
  const [gatewayState, setGatewayState] = useState<GatewayState>('caution');
  const [gatewayChecked, setGatewayChecked] = useState(false);

  useEffect(() => {
    setHistory(getScanHistory());
    const savedTheme = localStorage.getItem('online_guard_theme');
    if (savedTheme === 'dark' || savedTheme === 'light') setTheme(savedTheme);
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    localStorage.setItem('online_guard_theme', theme);
  }, [theme]);

  const selectPage = (next: Page) => {
    setPage(next);
    setMobileOpen(false);
    if (next !== 'gateway') setGatewayChecked(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleAnalysis = (result: AnalysisResult) => {
    setCurrentAnalysis(result);
    saveScanToHistory(result);
    setHistory(getScanHistory());
    selectPage('scanner');
  };

  const clearHistory = () => {
    clearScanHistory();
    setHistory([]);
  };

  const isAdmin = ['admin', 'mail'].includes(page);

  return (
    <div className="app-frame">
      <aside id="workspace-navigation" className={`app-sidebar ${mobileOpen ? 'mobile-open' : ''} ${sidebarOpen ? '' : 'app-sidebar-collapsed'}`}>
        <div className="brand-lockup" onClick={() => selectPage('scanner')} role="button" tabIndex={0}>
          <div className="brand-mark"><ShieldCheck size={20} /></div>
          {sidebarOpen && <div><strong>Safety Guard</strong><span>Online protection</span></div>}
        </div>

        <div className="sidebar-section-label">Workspace</div>
        <nav className="sidebar-nav" aria-label="Public navigation">
          {navPublic.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`sidebar-link ${page === id ? 'sidebar-link-active' : ''}`} onClick={() => selectPage(id)} title={label}>
              <Icon size={18} /><span>{sidebarOpen && label}</span>
              {id === 'history' && history.length > 0 && sidebarOpen && <b className="nav-count">{history.length}</b>}
            </button>
          ))}
        </nav>

        <div className="sidebar-section-label">Admin console</div>
        <nav className="sidebar-nav" aria-label="Admin navigation">
          {navAdmin.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`sidebar-link ${page === id ? 'sidebar-link-active' : ''}`} onClick={() => selectPage(id)} title={label}>
              <Icon size={18} /><span>{sidebarOpen && label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-spacer" />
        {sidebarOpen && <div className="sidebar-tip"><Shield size={17} /><div><strong>Your data stays private</strong><span>Scans are stored locally in this demo.</span></div></div>}
        <button className="sidebar-collapse" aria-label={sidebarOpen ? 'Collapse menu' : 'Expand menu'} title={sidebarOpen ? 'Collapse menu' : 'Expand menu'} onClick={() => setSidebarOpen(!sidebarOpen)}>{sidebarOpen ? <PanelLeftClose size={17} /> : <PanelLeftOpen size={17} />}<span>{sidebarOpen ? 'Collapse menu' : 'Expand menu'}</span></button>
      </aside>

      {mobileOpen && <button className="mobile-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <div className="app-main">
        <header className="topbar">
          <div className="topbar-left"><button className="mobile-menu" aria-label="Toggle navigation" aria-controls="workspace-navigation" aria-expanded={mobileOpen} onClick={() => { setSidebarOpen(true); setMobileOpen(!mobileOpen); }}><Menu size={20} /></button><span className="breadcrumb">{isAdmin ? 'Admin console' : page === 'gateway' ? 'Protected link' : 'Public workspace'}</span><ChevronRight size={14} /><strong>{pageTitle(page)}</strong></div>
          <div className="topbar-actions"><span className="service-status"><i /> Protection active</span><button className="icon-button" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')} aria-label="Toggle theme">{theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}</button><div className="avatar">AM</div></div>
        </header>

        <main className="content-wrap">
          {page === 'scanner' && <ScannerPage currentAnalysis={currentAnalysis} onAnalysis={handleAnalysis} onScanAnother={() => setCurrentAnalysis(null)} onInspect={(url) => { setSelectedUrl(url); selectPage('links'); }} />}
          {page === 'links' && <PageIntro eyebrow="URL checker" title="Inspect a link before you open it." description="Check a URL or domain against structure, reputation, and redirect signals. An incomplete check is always shown as unverified — never safe." icon={<Globe2 size={22} />}><DomainChecker initialUrl={selectedUrl} /></PageIntro>}
          {page === 'history' && <div className="page-content-glass"><ScanHistoryView history={history} onSelectScan={(scan) => { setCurrentAnalysis(scan); selectPage('scanner'); }} onClearHistory={clearHistory} onNewScan={() => { setCurrentAnalysis(null); selectPage('scanner'); }} /></div>}
          {page === 'emergency' && <PageIntro eyebrow="Emergency guidance" title="Know what to do next." description="Choose the situation that best matches what happened. Small, calm steps can limit damage quickly." icon={<CircleHelp size={22} />}><EmergencyGuide /></PageIntro>}
          {page === 'admin' && <AdminOverview onNavigate={selectPage} />}
          {page === 'mail' && <MailActivity />}
          {page === 'gateway' && <GatewayPage state={gatewayState} checked={gatewayChecked} onCheck={() => { setGatewayChecked(true); setGatewayState('checking'); setTimeout(() => setGatewayState('caution'), 900); }} onStateChange={setGatewayState} />}
        </main>

        <footer className="app-footer"><span><LockKeyhole size={14} /> Safety Guard uses clear, explainable checks. Never treat an unverified result as proof of safety.</span><button onClick={() => selectPage('gateway')}>Preview protected link gateway <ArrowRight size={14} /></button></footer>
      </div>
    </div>
  );
}

function pageTitle(page: Page) {
  const item = [...navPublic, ...navAdmin].find((n) => n.id === page);
  return item?.label || (page === 'gateway' ? 'Gateway preview' : 'Dashboard');
}

function PageIntro({ eyebrow, title, description, icon, children }: { eyebrow: string; title: string; description: string; icon: React.ReactNode; children: React.ReactNode }) {
  return <section className="page-section"><div className="page-heading"><div className="eyebrow"><span className="eyebrow-icon">{icon}</span>{eyebrow}</div><h1>{title}</h1><p>{description}</p></div><div className="page-content-glass">{children}</div></section>;
}

function AdminPageIntro({ eyebrow, title, description, icon, children }: { eyebrow: string; title: string; description: string; icon: React.ReactNode; children: React.ReactNode }) {
  return <section className="page-section admin-page"><div className="page-heading"><div className="eyebrow"><span className="eyebrow-icon">{icon}</span>{eyebrow}</div><h1>{title}</h1><p>{description}</p></div><div className="admin-content-surface">{children}</div></section>;
}

function ScannerPage({ currentAnalysis, onAnalysis, onScanAnother, onInspect }: { currentAnalysis: AnalysisResult | null; onAnalysis: (r: AnalysisResult) => void; onScanAnother: () => void; onInspect: (url: string) => void }) {
  return <section className="page-section"><div className="scanner-hero"><div><div className="eyebrow"><span className="eyebrow-icon"><ShieldAlert size={18} /></span>Message scanner</div><h1>Make the suspicious<br /><em>feel explainable.</em></h1><p>Paste a message, upload a screenshot, and get a clear risk assessment before you respond or click.</p><div className="hero-trust"><span><CheckCircle2 size={15} /> Explainable signals</span><span><LockKeyhole size={15} /> Private by design</span><span><Activity size={15} /> Fast analysis</span></div></div><div className="hero-orbit"><div className="orbit-ring orbit-ring-one" /><div className="orbit-ring orbit-ring-two" /><div className="hero-shield"><ShieldCheck size={54} /></div><span className="orbit-chip chip-top"><AlertTriangle size={14} /> Red flags</span><span className="orbit-chip chip-bottom"><Link2 size={14} /> Link check</span></div></div>{currentAnalysis ? <AnalysisReport result={currentAnalysis} onScanAnother={onScanAnother} onInspectDomain={onInspect} /> : <MessageScanner onAnalysisComplete={onAnalysis} />}</section>;
}

function AdminOverview({ onNavigate }: { onNavigate: (p: Page) => void }) {
  return <AdminPageIntro eyebrow="Admin console" title="A quieter view of your protection layer." description="Review inspected links, mail security events, and policy decisions from one place." icon={<LayoutDashboard size={22} />}><div className="stat-grid">{statCards.map(({ label, value, trend, icon: Icon, tone }) => <div className={`stat-card stat-${tone}`} key={label}><div className="stat-icon"><Icon size={18} /></div><span>{label}</span><strong>{value}</strong><small>{trend}</small></div>)}</div><div className="admin-grid"><section className="panel"><div className="panel-header"><div><span className="panel-kicker">Recent inspections</span><h2>Link activity</h2></div><a className="text-button" href="/admin">Manage lists <ArrowRight size={14} /></a></div><div className="activity-list"><ActivityRow domain="secure-account-check.com/login" source="Outlook · order-4821" status="blocked" time="4 min ago" /><ActivityRow domain="notion.so/workspace/invite" source="Gmail · team-update" status="safe" time="18 min ago" /><ActivityRow domain="paypaI-verification.net" source="Outlook · billing-alert" status="caution" time="42 min ago" /><ActivityRow domain="docs.google.com/forms/d/e/…" source="Mail activity · hiring" status="safe" time="1 hr ago" /></div></section><section className="panel review-panel"><div className="panel-header"><div><span className="panel-kicker">Needs attention</span><h2>Review queue</h2></div><span className="queue-badge">14 open</span></div><div className="review-item"><div className="review-symbol review-symbol-amber"><AlertTriangle size={17} /></div><div><strong>Unverified destination</strong><p>cdn-customer-support.co</p><small>Reported from Mail Activity</small></div><MoreHorizontal size={18} /></div><div className="review-item"><div className="review-symbol review-symbol-red"><ShieldAlert size={17} /></div><div><strong>New blocked domain</strong><p>microsoft-security-alerts.top</p><small>3 messages · 12 recipients</small></div><MoreHorizontal size={18} /></div><button className="wide-button" onClick={() => onNavigate('mail')}>Open mail activity <ArrowRight size={15} /></button></section></div></AdminPageIntro>;
}

function ActivityRow({ domain, source, status, time }: { domain: string; source: string; status: 'blocked' | 'caution' | 'safe'; time: string }) { return <div className="activity-row"><div className="activity-domain"><div className="domain-favicon"><Globe2 size={15} /></div><div><strong>{domain}</strong><span>{source}</span></div></div><StatusPill status={status} /><time>{time}</time></div>; }

function MailActivity() { return <AdminPageIntro eyebrow="Admin console / Mail activity" title="Reported email security events." description="These events represent reports from an existing mail integration. No inbox access is created here." icon={<Mail size={22} />}><div className="mail-toolbar"><div className="search-field"><Search size={16} /><input placeholder="Search sender, subject, or event ID" /></div><select defaultValue="all"><option value="all">All statuses</option><option>Blocked</option><option>Needs review</option><option>Safe</option></select><button className="secondary-button">Last 30 days <ChevronRight size={14} /></button><a className="text-button" href="/admin/mail" target="_blank" rel="noopener noreferrer">Open live mail activity <ExternalLink size={14} /></a></div><p className="sample-data-note">The table below is sample data illustrating the layout. Real events, with sign-in required, are at <a href="/admin/mail" target="_blank" rel="noopener noreferrer">/admin/mail</a>.</p><div className="panel table-panel"><table><thead><tr><th>Event</th><th>Source</th><th>Related links</th><th>Status</th><th>Received</th></tr></thead><tbody><tr><td><strong>Suspicious invoice follow-up</strong><span>evt_01HZX82A · 3 links found</span></td><td>Outlook</td><td><button className="link-button">2 inspected links</button></td><td><StatusPill status="blocked" /></td><td>Today, 09:42</td></tr><tr><td><strong>Workspace invitation</strong><span>evt_01HZX761 · 1 link found</span></td><td>Gmail</td><td><button className="link-button">1 inspected link</button></td><td><StatusPill status="safe" /></td><td>Today, 08:18</td></tr><tr><td><strong>Account verification notice</strong><span>evt_01HZWQ90 · 1 link found</span></td><td>Outlook</td><td><button className="link-button">1 inspected link</button></td><td><StatusPill status="caution" /></td><td>Yesterday, 17:06</td></tr></tbody></table></div></AdminPageIntro>; }


function GatewayPage({ state, checked, onCheck, onStateChange }: { state: GatewayState; checked: boolean; onCheck: () => void; onStateChange: (s: GatewayState) => void }) { const isBlocked = state === 'blocked'; const isSafe = state === 'safe'; return <section className="gateway-page"><div className="gateway-card"><div className={`gateway-icon gateway-icon-${state}`}>{state === 'blocked' ? <XCircle size={30} /> : state === 'safe' ? <ShieldCheck size={30} /> : state === 'checking' ? <Activity size={30} /> : <AlertTriangle size={30} />}</div><span className="eyebrow">Protected link gateway</span><h1>{state === 'checking' ? 'Checking this link…' : state === 'blocked' ? 'This destination is blocked.' : state === 'safe' ? 'This link passed its checks.' : 'Pause before you continue.'}</h1><p>{state === 'checking' ? 'We are checking the destination and redirect chain. This page will update automatically.' : isBlocked ? 'Safety Guard found a high-risk signal. Do not enter information or continue to the destination.' : isSafe ? 'The configured checks did not find a known threat. Stay alert for requests for passwords, payments, or codes.' : 'This link could not be fully verified. Treat the destination as suspicious until you confirm it through an official channel.'}</p><div className="gateway-url"><Link2 size={16} /><span>https://secure-account-check.com/login</span></div><div className="gateway-checks"><span><CheckCircle2 size={14} /> URL structure</span><span className={state === 'blocked' ? 'check-fail' : ''}>{state === 'blocked' ? <XCircle size={14} /> : <AlertTriangle size={14} />} Reputation lookup</span><span><AlertTriangle size={14} /> Redirect chain</span></div>{!checked && <button className="primary-button gateway-button" onClick={onCheck}>Check destination <ArrowRight size={16} /></button>}{checked && !isBlocked && !isSafe && <div className="gateway-actions"><button className="secondary-button" onClick={() => onStateChange('blocked')}>Keep me safe</button><button className="primary-button" onClick={() => onStateChange('safe')}>Continue anyway <ExternalLink size={15} /></button></div>}{checked && isBlocked && <div className="blocked-note"><LockKeyhole size={15} /> No destination link is provided for blocked results.</div>}{checked && isSafe && <button className="primary-button" onClick={() => onStateChange('caution')}>Return to caution state</button>}<div className="gateway-demo-controls"><span>Demo state</span><button onClick={() => { onStateChange('caution'); }} className={state === 'caution' ? 'active' : ''}>Caution</button><button onClick={() => onStateChange('blocked')} className={state === 'blocked' ? 'active' : ''}>Blocked</button><button onClick={() => onStateChange('safe')} className={state === 'safe' ? 'active' : ''}>Safe</button></div></div></section>; }

export default App;
