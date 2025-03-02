import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Login from "./pages/Login.jsx";
// import Home from "./pages/Home.jsx";
// import Profile from "./pages/Profile.jsx";
import Wallet from "./pages/Wallet.jsx";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/Wallet" element={<Wallet />} />
        <Route path="/login" element={<Login />} />
    
      </Routes>
    </Router>
  );
}

export default App;