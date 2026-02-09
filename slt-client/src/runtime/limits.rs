use slt_core::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, AUTH_PAYLOAD_LEN, HP_KEY_LEN, MAX_DCID_LEN, MessageLimits,
};

pub(super) fn message_limits_from_mtu(mtu: u16) -> MessageLimits {
    let max_data_len = mtu as usize;
    let max_register_len = 1
        + MAX_DCID_LEN
        + 1
        + MAX_DCID_LEN
        + 1
        + (HP_KEY_LEN * 2)
        + (AEAD_KEY_LEN * 2)
        + (AEAD_IV_LEN * 2)
        + 8
        + 8
        + 1;
    let max_frame_len = max_data_len.max(max_register_len).max(AUTH_PAYLOAD_LEN);
    MessageLimits::new(max_frame_len, max_data_len)
}
