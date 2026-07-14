import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Overview from './pages/Overview';
import Threats from './pages/Threats';
import Timeline from './pages/Timeline';
import Processes from './pages/Processes';
import Modules from './pages/Modules';
import Network from './pages/Network';
import KernelIntegrity from './pages/KernelIntegrity';
import Memory from './pages/Memory';
import Forensics from './pages/Forensics';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/threats" element={<Threats />} />
        <Route path="/timeline" element={<Timeline />} />
        <Route path="/processes" element={<Processes />} />
        <Route path="/modules" element={<Modules />} />
        <Route path="/network" element={<Network />} />
        <Route path="/kernel" element={<KernelIntegrity />} />
        <Route path="/memory" element={<Memory />} />
        <Route path="/forensics" element={<Forensics />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  );
}
