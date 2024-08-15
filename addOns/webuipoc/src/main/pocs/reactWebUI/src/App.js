import "./App.css";
import React, { useState, useEffect } from "react";
import axios from "axios";
import Sidebar from "./Components/Sidebar/Sidebar";
import HeaderBase from "./Components/Header/HeaderBase";
import SideTree from "./Components/SitesTree/SitesTree";
import RequestBar from "./Components/Request-Response/Req-Resp-Bar";
import SearchBar from "./Components/SearchBar/SearchBar";
import History from "./Components/History/History";


const App = () => {

  return (
    <div className="flex mt-16 overflow-auto">
      <HeaderBase />
      <Sidebar />
      <SideTree />

      <div className="w-full bg-gray-600 text-white ">
        <SearchBar />
        <RequestBar />
        <History />

   </div>
   </div>
  );
};

export default App;
