import React, { useContext } from 'react';
import { useState,useEffect} from "react";
import { sendMessage } from "../../Utilities/req-resp";
import { nodeIDContext } from '../../Contexts/SitesTreeNodeIDContext';


function reqResp() {

  const [initialreqRep, setinitialreqRep] = useState(null)
  const {nodeID} = useContext(nodeIDContext)

  useEffect(() => {
      const fetchData = async () => {
        try {
          const response = await sendMessage(nodeID);
          setinitialreqRep(response);
        } catch (error) {
          console.error("Error fetching data:", error);
        }
      };
      if (nodeID != 0) {fetchData();} 
      
    }, [nodeID]);




  return (
    <div className="w-full bg-gray-600 text-white mt-2">
      
      <div className="flex flex-row mr-2"> 
        
      <div className='h-[594px] w-1/2 ml-2 bg-gray-700 rounded-lg overflow-scroll'>
          <div className="flex flex-row text-center justify-center ">
            <div className="w-1/3 p-4 font-serif text-center">Request</div>
          </div>     
          <div className="flex justify-center text-center">
              <div className="p-4 overflow-x-auto">  {initialreqRep?.requestHeader}  </div>          
          </div>
          
          <p className=" justify-center text-center overflow-x-auto">{initialreqRep?.requestBody}</p>
           </div>
        
       
        <div className='h-[594px] w-1/2 ml-2 bg-gray-700 rounded-lg overflow-scroll'>
          <div className="flex flex-row text-center justify-center">
            <div className="w-1/3 p-4 font-serif text-center">Response</div>
          </div>            
          <div className="flex justify-center text-center">
              <div className="p-4 overflow-x-auto">  {initialreqRep?.responseHeader}  </div>          
          </div>
          
          <p className=" p-4 justify-center text-center overflow-x-auto">{initialreqRep?.responseBody}</p>
       
        </div>
      
      </div> 
    </div>
  );
}

export default reqResp;
