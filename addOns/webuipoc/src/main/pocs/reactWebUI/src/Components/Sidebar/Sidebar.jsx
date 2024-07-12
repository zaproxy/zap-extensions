import React from 'react';
import { SidebarData } from './SidebarData';

function Sidebar() {
  return (
    <div className='Sidebar w-10 bg-gray-800 '>
      <ul className='SidebarList h-auto p-0 w-full '>
        {SidebarData.map((val, key) => {
          return (
            <li 
            key={key}
               className="row w-full h-10  text-white list-none m-0 flex  items-center  justify-left  hover:bg-gray-700"
              onClick={() => {
                window.location.pathname =val.ink
              }}>
              
             <div className='SidebarIcon flex  justify-center items-center ml-2' > {val.icon}</div>
             <div className='SidebarTitle ml-2'> {val.title}</div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export default Sidebar;
