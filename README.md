# Open5gs - Malformated UE initial message crashes AMF causing DoS
Recently, we discovered a vulnerability that may cause Open5gs AMF to crash during a code audit of Open5gs Ver2.4.11. 
The specific causes of the vulnerability are as follows:

## Vulnerability description
When processing UE attachment, a memory leak in AMF `ngap-handler.c` from open5gs causing a DoS vulnerability.
### ngap-handler

UE initial message is handled by function `ngap_handle_initial_ue_message` from `src/amf/ngap-handler.c`.

> src/amf/ngap-handler.c
```c=334
void ngap_handle_initial_ue_message(amf_gnb_t *gnb, ogs_ngap_message_t *message)
{
    ...
```
`RAN_UE_NGAP_ID` and `UserLocationInformation` is extracted from `InitialUEMessage`.
```c=363
    for (i = 0; i < InitialUEMessage->protocolIEs.list.count; i++) {
        ie = InitialUEMessage->protocolIEs.list.array[i];
        switch (ie->id) {
        case NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID:
            RAN_UE_NGAP_ID = &ie->value.choice.RAN_UE_NGAP_ID;
            break;
        case NGAP_ProtocolIE_ID_id_NAS_PDU:
            NAS_PDU = &ie->value.choice.NAS_PDU;
            break;
        case NGAP_ProtocolIE_ID_id_UserLocationInformation:
            UserLocationInformation =
                &ie->value.choice.UserLocationInformation;
            break;
        ...
    
```
`ran_ue` structure will be allocated and assigned after validating `RAN_UE_NGAP_ID` by calling `ran_ue_add`.

```c=390
    if (!RAN_UE_NGAP_ID) {
        ogs_error("No RAN_UE_NGAP_ID");
        ogs_assert(OGS_OK ==
            ngap_send_error_indication(gnb, NULL, NULL,
                NGAP_Cause_PR_protocol, NGAP_CauseProtocol_semantic_error));
        return;
    }

    ran_ue = ran_ue_find_by_ran_ue_ngap_id(gnb, *RAN_UE_NGAP_ID);
    if (!ran_ue) {
        ran_ue = ran_ue_add(gnb, *RAN_UE_NGAP_ID);
        ogs_assert(ran_ue);
        ...
```

If `UserLocationInformation` is not present, the function will return and `ran_ue_remove` will never be called, here is the memory leak bug.

```c=463
    if (!UserLocationInformation) {
        ogs_error("No UserLocationInformation");
        ogs_assert(OGS_OK ==
            ngap_send_error_indication(gnb, &ran_ue->ran_ue_ngap_id, NULL,
                NGAP_Cause_PR_protocol, NGAP_CauseProtocol_semantic_error));
        return;
    }
    ...
}
```

### UE_ADD UE_POOL

Pool `ran_ue_pool` is initialed by `amf_context_init` from `src/amf/context.c` on line 61. 

> src/amf/context.c

```c=61
    ogs_pool_init(&ran_ue_pool, ogs_app()->max.ue);
```

When calling `ran_ue_add`, `ran_ue` will be allocated.

```c=966
ran_ue_t *ran_ue_add(amf_gnb_t *gnb, uint32_t ran_ue_ngap_id)
{
    ran_ue_t *ran_ue = NULL;

    ogs_assert(gnb);

    ogs_pool_alloc(&ran_ue_pool, &ran_ue);
    ogs_assert(ran_ue);
    memset(ran_ue, 0, sizeof *ran_ue);
    ...
```
```c=1002
    ogs_list_add(&gnb->ran_ue_list, ran_ue);

    stats_add_ran_ue();

    return ran_ue;
}
```

One must call `ran_ue_remove` after ue_add to free the `ran_ue`.
```c=1009
void ran_ue_remove(ran_ue_t *ran_ue)
{
    ogs_assert(ran_ue);
    ogs_assert(ran_ue->gnb);

    ogs_list_remove(&ran_ue->gnb->ran_ue_list, ran_ue);

    ogs_assert(ran_ue->t_ng_holding);
    ogs_timer_delete(ran_ue->t_ng_holding);

    ogs_pool_free(&ran_ue_pool, ran_ue);

    stats_remove_ran_ue();
}
```

`max.ue` is defined 1024 as default.

> lib/ogs-context.c

```c=168
static void app_context_prepare(void)
{
    ...

#define MAX_NUM_OF_UE               1024    /* Num of UEs */
#define MAX_NUM_OF_PEER             64      /* Num of Peer */

    self.max.ue = MAX_NUM_OF_UE;
    ...
}
```

## POC

To trigger this vulnerability, an `InitialUEMessage` without `UserLocationInformation` needs to be build.


![](https://github.com/ToughRunner/Open5gs_bugreport2/blob/main/1.png)

AMF will crash after 1024 malformated UE initial messages is reached.

![](https://github.com/ToughRunner/Open5gs_bugreport2/blob/main/2.png)

## Upadate
We have reported this vulnerability to the vendor through email at 19 Sep 2022, but this bug has not been fixed yet.

## Acknowledgment
Credit to @ToughRunner,@HenryzhaoH,@leonW7 from Shanghai Jiao Tong University.

