#include <iostream>
#include <exception>
#include "EncryptedMessenger.h"

int main() {
    EncryptedMessenger messagingClient;
    
    // Initalize client
    if (!messagingClient.init()) {
        std::cerr << "ERROR: Unable to initialize the messaging client. Exiting application." << std::endl;
        return EXIT_FAILURE;
    }
    
    try {
        messagingClient.run();
    }
    catch (const std::exception& ex) {
        std::cerr << "CRITICAL ERROR: " << ex.what() << std::endl;
        messagingClient.close();
        return EXIT_FAILURE;
    }
    catch (...) {
        std::cerr << "CRITICAL ERROR: Unknown exception occurred" << std::endl;
        messagingClient.close();
        return EXIT_FAILURE;
    }
    
    // Close client when done
    messagingClient.close();
    return EXIT_SUCCESS;
}
