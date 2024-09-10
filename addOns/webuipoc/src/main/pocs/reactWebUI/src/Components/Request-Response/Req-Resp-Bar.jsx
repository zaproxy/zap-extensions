import React from 'react';

function ResponseBar() {
  return (

    <div className="w-full bg-gray-600 text-white">
      
      <div className="flex flex-row mr-2"> 
        
      <div className='h-[500px] w-1/2 ml-2 bg-gray-700 rounded-lg overflow-scroll'>

          <div className="flex flex-row text-center justify-center ">
            <div className="w-1/3 p-4 font-serif text-center">Request</div>
          </div>            
          <div className="flex justify-center text-center">
            <div className="p-4">
              <p className='font-mono'>############</p>
            </div>
          </div>
        </div>
        
       

        <div className='h-[500px] w-1/2 ml-2 bg-gray-700 rounded-lg overflow-scroll'>
          <div className="flex flex-row text-center justify-center">
            <div className="w-1/3 p-4 font-serif text-center">Response</div>
          </div>            
          <div className="flex justify-center text-center">
            <div className="p-4">
              <p className='font-mono'>#############</p>
            </div>
          </div>
        </div>
      
      </div> 
    </div>
  );
}

export default ResponseBar;
