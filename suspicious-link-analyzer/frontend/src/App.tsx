import { Routes, Route } from 'react-router-dom';
import { UserProvider } from '@/services/userContext';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import Dashboard from '@/pages/Dashboard';
import ScanResult from '@/pages/ScanResult';
import ScanHistory from '@/pages/ScanHistory';
import DetailedReport from '@/pages/DetailedReport';
import DemoMode from '@/pages/DemoMode';
import NotFound from '@/pages/NotFound';

export default function App() {
  return (
    <UserProvider>
      <div className="min-h-screen flex flex-col bg-slate-950">
        <Navbar />
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan/:id" element={<ScanResult />} />
            <Route path="/history" element={<ScanHistory />} />
            <Route path="/report/:id" element={<DetailedReport />} />
            <Route path="/demo" element={<DemoMode />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </UserProvider>
  );
}
