import React, { useState, useEffect } from "react";
import {sendHistory} from "../../Utilities/history"


const History = () => {
  const [history, setHistory] = useState(null)
  

  useEffect(() => {
      const fetchData = async () => {
        try {
          const response = await sendHistory();
          setHistory(response);
        } catch (error) {
          console.error("Error fetching data:", error);
        }
      };

      fetchData();
    }, []);

return (
  <div className="h-[496px]  mr-2 ml-2 mt-2 bg-gray-800 rounded-lg overflow-auto">
  <div className="flex flex-row text-center justify-center ">
    <div className=" w-1/3 p-4 font-serif text-center ">
    History
    </div>
  </div>
  <div className="w-full overflow-auto">
  <div className="overflow-x-auto">
    <table className="min-w-full bg-gray-700 text-white">
      <thead className="bg-gray-800 text-white sticky top-0">


          <tr>
            <th className="py-3 px-4 border-b">ID</th>
            <th className="py-3 px-4 border-b">Method</th>
            <th className="py-3 px-4 border-b">Date & Time</th>
            <th className="py-3 px-4 border-b">URL</th>
            <th className="py-3 px-4 border-b">Code</th>
            <th className="py-3 px-4 border-b">Reason</th>
            <th className="py-3 px-4 border-b">Size</th>

          </tr>
        </thead>
        <tbody>
       {
        history?.log?.entries?.map((historyElement) => (
          <tr className="">
          <td className="py-3 px-4">{historyElement._zapMessageId}</td>
          <td className="py-3 px-4">{historyElement.request?.method}</td>
          <td className="py-3 px-4">{historyElement.startedDateTime}</td>
          <td className="py-3 px-4">{historyElement.request?.url}</td>
          <td className="py-3 px-4">{historyElement.response?.status}</td>
          <td className="py-3 px-4">{historyElement.response?.statusText}</td>
          <td className="py-3 px-4">{historyElement.response?.bodySize} bytes</td>
        </tr>
                  )) }
          
        </tbody>
      </table>
    </div>
    </div>
</div>
  );
};

export default History;
