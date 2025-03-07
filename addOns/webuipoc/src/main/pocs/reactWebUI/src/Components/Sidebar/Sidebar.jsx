import React from "react";
import { SidebarData } from "./SidebarData";

const Sidebar = ({ darkMode, setDarkMode }) => {
  const toggleDarkMode = () => {
    setDarkMode(prevMode => !prevMode);
  };

  return (
    <div className="Sidebar w-10 bg-gray-800 ">
      <ul className="SidebarList h-auto p-0 w-full ">
        {SidebarData.map((val, key) => {
          return (
            <li
              key={key}
              className="row w-full h-10  text-white list-none m-0 flex  items-center  justify-left  hover:bg-gray-700"
              onClick={() => {
                window.location.pathname = val.ink;
              }}
            >
              <div className="SidebarIcon flex  justify-center items-center ml-2">
                {" "}
                {val.icon}
              </div>
              <div className="SidebarTitle ml-2"> {val.title}</div>
            </li>
          );
        })}
      </ul>
      <button
        onClick={toggleDarkMode}
        className="mt-4 p-2 text-gray-300 hover:text-white"
      >
        {darkMode ? (
          <span className="text-xl">🔅 </span>
        ) : (
          <span className="text-xl">🌒</span>
        )}
      </button>
    </div>
  );
}

export default Sidebar;
