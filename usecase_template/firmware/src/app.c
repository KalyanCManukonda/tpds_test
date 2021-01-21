/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app.c

  Summary:
    This file contains the source code for the MPLAB Harmony application.

  Description:
    This file contains the source code for the MPLAB Harmony application.  It
    implements the logic of the application's state machine and it may call
    API routines of other MPLAB Harmony modules in the system, such as drivers,
    system services, and middleware.  However, it does not call any of the
    system interfaces (such as the "Initialize" and "Tasks" functions) of any of
    the modules in the system or make any assumptions about when those functions
    are called.  That is the responsibility of the configuration-specific system
    files.
 *******************************************************************************/

/*******************************************************************************
* Copyright (C) 2019 Microchip Technology Inc. and its subsidiaries.
*
* Subject to your compliance with these terms, you may use Microchip software
* and any derivatives exclusively with Microchip products. It is your
* responsibility to comply with third party license terms applicable to your
* use of third party software (including open source software) that may
* accompany Microchip software.
*
* THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
* EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
* WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
* PARTICULAR PURPOSE.
*
* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
* FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN
* ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
* THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
*******************************************************************************/
// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include "app.h"
#include "cryptoauthlib.h"
#include "host/atca_host.h"
#include "../../template_resources.h"

// *****************************************************************************
// *****************************************************************************
// Section: Global Data Definitions
// *****************************************************************************
// *****************************************************************************
extern ATCAIfaceCfg atecc608_0_init_data;
extern uint8_t template_key[];
uint8_t num_in[NONCE_NUMIN_SIZE];
uint8_t rand_out[RANDOM_NUM_SIZE];
uint8_t device_mac[MAC_SIZE];
uint8_t host_mac[MAC_SIZE];

// *****************************************************************************
/* Application Data

  Summary:
    Holds application data

  Description:
    This structure holds the application's data.

  Remarks:
    This structure should be initialized by the APP_Initialize function.

    Application strings and buffers are be defined outside this structure.
*/

APP_DATA appData;

// *****************************************************************************
// *****************************************************************************
// Section: Application Local Functions
// *****************************************************************************
// *****************************************************************************
int RNG(uint8_t *dest, unsigned size)
{
    return 1;
}

ATCA_STATUS generate_device_mac(void)
{
    ATCA_STATUS status;
    char displaystr[400];
    size_t displaylen;

    RNG(num_in, 20);
    status = atcab_nonce_rand(num_in, rand_out);
    if (status == ATCA_SUCCESS)
    {
        printf("\nDevice nonce generation is successful.\r\n");
        status = atcab_mac(MAC_MODE_BLOCK2_TEMPKEY | MAC_MODE_INCLUDE_SN, SLOT_NUMBER, NULL, device_mac);
        if (status == ATCA_SUCCESS)
        {
            displaylen = sizeof(displaystr);
            atcab_bin2hex(device_mac, MAC_SIZE, displaystr, &displaylen);
            printf("\nMAC received from device:\r\n%s\r\n", displaystr);
        }
        else
        {
            printf("\nDevice mac calculation is failed{%02X}.\r\n", status);
        }
    }
    else
    {
        printf("\nDevice nonce generation is failed{%02X}.\r\n", status);
    }

    return status;
}

ATCA_STATUS calculate_host_mac(void)
{
    ATCA_STATUS status;
    atca_temp_key_t temp_key;
    atca_nonce_in_out_t nonce_params;
    atca_mac_in_out_t mac_params;
    uint8_t sn[ATCA_SERIAL_NUM_SIZE];
    char displaystr[400];
    size_t displaylen;

    // Setup nonce command
    memset(&temp_key, 0, sizeof(temp_key));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    status = atcah_nonce(&nonce_params);
    if (status == ATCA_SUCCESS)
    {
        printf("\nHost nonce generation is successful.\r\n");
        status = atcab_read_serial_number(sn);
        if (status == ATCA_SUCCESS)
        {
            // Setup MAC command
            memset(&mac_params, 0, sizeof(mac_params));
            mac_params.mode = MAC_MODE_BLOCK2_TEMPKEY | MAC_MODE_INCLUDE_SN; // Block 1 is a key, block 2 is TempKey
            mac_params.key_id = SLOT_NUMBER;
            mac_params.challenge = NULL;
            mac_params.key = template_key;
            mac_params.otp = NULL;
            mac_params.sn = sn;
            mac_params.response = host_mac;
            mac_params.temp_key = &temp_key;
            status = atcah_mac(&mac_params);
            if (status == ATCA_SUCCESS)
            {
                displaylen = sizeof(displaystr);
                atcab_bin2hex(device_mac, MAC_SIZE, displaystr, &displaylen);
                printf("\nMAC calculated on Host:\r\n%s\r\n", displaystr);
            }
            else
            {
                printf("\nHost mac calculation is failed{%02X}.\r\n", status);
            }
        }
        else
        {
            printf("\nReading serial number is failed{%02X}.\r\n", status);
        }
    }
    else
    {
        printf("\nHost nonce generation is failed{%02X}.\r\n", status);
    }

    return status;
}

ATCA_STATUS compare_mac(void)
{
    ATCA_STATUS status;

    if(memcmp(device_mac, host_mac, MAC_SIZE) == 0)
    {
        status = ATCA_SUCCESS;
        printf("\nApplication authentication is successful.\r\n");
    }
    else
    {
        status = ATCA_CHECKMAC_VERIFY_FAILED;
        printf("\nApplication authentication is failed{%02X}.\r\n", status);
    }

    return status;
}

// *****************************************************************************
// *****************************************************************************
// Section: Application Initialization and State Machine Functions
// *****************************************************************************
// *****************************************************************************

/*******************************************************************************
  Function:
    void APP_Initialize ( void )

  Remarks:
    See prototype in app.h.
 */

void APP_Initialize(void)
{
    /* Place the App state machine in its initial state. */
    appData.state = APP_STATE_INIT;
}

/******************************************************************************
  Function:
    void APP_Tasks ( void )

  Remarks:
    See prototype in app.h.
 */
void APP_Tasks(void)
{
    ATCA_STATUS status;

    switch(appData.state)
    {
        case APP_STATE_INIT:
            status = atcab_init(&atecc608_0_init_data);
            appData.state = (status == ATCA_SUCCESS) ? APP_STATE_GENERATE_DEVICE_MAC : APP_STATE_FINISH;
            break;

        case APP_STATE_GENERATE_DEVICE_MAC:
            status = generate_device_mac();
            appData.state = (status == ATCA_SUCCESS) ? APP_STATE_CALCULATE_HOST_MAC : APP_STATE_FINISH;
            break;

        case APP_STATE_CALCULATE_HOST_MAC:
            status = calculate_host_mac();
            appData.state = (status == ATCA_SUCCESS) ? APP_STATE_COMPARE_MAC : APP_STATE_FINISH;
            break;

        case APP_STATE_COMPARE_MAC:
            (void)compare_mac();
            appData.state = APP_STATE_FINISH;
            break;

        case APP_STATE_FINISH:
        /* Intentional fall through */
        default:
            /* Nothing to do */
            break;
    }
}

/*******************************************************************************
 End of File
 */
