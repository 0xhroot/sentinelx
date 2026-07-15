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
import LiveMonitor from './pages/LiveMonitor';
import Telemetry from './pages/Telemetry';
import Fleet from './pages/Fleet';
import Intelligence from './pages/Intelligence';
import Response from './pages/Response';
import Policies from './pages/Policies';

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/live" element={<LiveMonitor />} />
        <Route path="/threats" element={<Threats />} />
        <Route path="/timeline" element={<Timeline />} />
        <Route path="/intelligence" element={<Intelligence />} />
        <Route path="/processes" element={<Processes />} />
        <Route path="/network" element={<Network />} />
        <Route path="/memory" element={<Memory />} />
        <Route path="/modules" element={<Modules />} />
        <Route path="/kernel" element={<KernelIntegrity />} />
        <Route path="/telemetry" element={<Telemetry />} />
        <Route path="/response" element={<Response />} />
        <Route path="/fleet" element={<Fleet />} />
        <Route path="/forensics" element={<Forensics />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  );
}
