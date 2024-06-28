import './App.css';
import React, { useState } from 'react';
import axios from 'axios';
import Sidebar from './Components/Sidebar/Sidebar';

const App = () => {
    const [childNode,setChildNode] = useState(null);
    const WebClickZAP = async () => {

        try {
            if (process.env.NODE_ENV === "development") {
             axios.defaults.baseURL = "http://localhost:1337"; //Specify ZAP API URL here in development environment
            } else {
                axios.defaults.baseURL = ""
            }

            const response = await axios.get('/JSON/core/view/childNodes/');
            setChildNode(response.data.childNodes);
        } catch (error) {
            console.error('Error fetching data:', error);
        }
    };
 return (

        <div className="flex">   
        <Sidebar />
        
            <div className="w-full bg-gray-600 text-white ">
                <div className='h-screen w-[400px] ml-2 bg-gray-800  '>
                <div className="flex flex-row text-center justify-center ">
                   <div className=" w-1/3 p-4 font-serif text-center ">Website</div>
                </div>            
                <div className="flex flex-row  justify-center text-center">
                    <div className=" p-4" onClick={WebClickZAP}>
                      <p className='font-mono '>Click to fetch</p>
                      {childNode && childNode.map((node) => (
                     <p className='' key={childNode}>{node.name}</p>
                      ))}
                    </div>
                </div>
            </div>
        </div>

        </div>

    );
}

export default App; 
