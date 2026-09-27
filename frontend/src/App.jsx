import { Routes, Route } from 'react-router-dom'
import Home from './pages/Home.jsx'
import ScanResults from './pages/ScanResults.jsx'
import DataFlow from './pages/DataFlow.jsx'
import FlowResults from './pages/FlowResults.jsx'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/flow" element={<FlowResults />} />
      <Route path="/scans/:scanId" element={<ScanResults />} />
      <Route path="/scans/:scanId/data-flow" element={<DataFlow />} />
    </Routes>
  )
}
