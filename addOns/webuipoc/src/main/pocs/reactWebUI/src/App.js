import "./App.css";
import React, { useState, useEffect } from "react";
import Sidebar from "./Components/Sidebar/Sidebar";
import HeaderBase from "./Components/Header/HeaderBase";
import SideTree from "./Components/SitesTree/SitesTree";
import RequestBar from "./Components/Request-Response/Req-Resp-Bar";
import SearchBar from "./Components/SearchBar/SearchBar";
import History from "./Components/History/History";


const App = () => {
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    const savedMode = localStorage.getItem('darkMode') === 'true';
    setDarkMode(savedMode);
  }, []);

  useEffect(() => {
    localStorage.setItem('darkMode', darkMode);
  }, [darkMode]);

  return (
    <div className={`flex mt-16 overflow-auto ${darkMode ? 'dark' : ''}`}>
      <Sidebar darkMode={darkMode} setDarkMode={setDarkMode} />
      <HeaderBase />
      <SideTree />
      <div className="w-full bg-gray-600 text-white dark:text-black">
        <SearchBar />
        <RequestBar />
        <History />

   </div>
   </div>
  );
};

export default App;
