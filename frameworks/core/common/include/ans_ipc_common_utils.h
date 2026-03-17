/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef BASE_NOTIFICATION_ANS_STANDARD_CORE_IPC_COMMON_UTILS_H
#define BASE_NOTIFICATION_ANS_STANDARD_CORE_IPC_COMMON_UTILS_H

#include <securec.h>

#include "ans_log_wrapper.h"
#include "ans_const_define.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class AnsIpcCommonUtils {
public:
    template<typename T>
    static bool WriteParcelableVector(const std::vector<std::shared_ptr<T>> &parcelableVector, Parcel &data)
    {
        if (!data.WriteInt32(parcelableVector.size())) {
            ANS_LOGE("Failed to write ParcelableVector size.");
            return false;
        }

        for (auto &parcelable : parcelableVector) {
            if (!data.WriteParcelable(parcelable.get())) {
                ANS_LOGE("Failed to write ParcelableVector");
                return false;
            }
        }
        return true;
    }

    template<typename T>
    static bool ReadParcelableVector(std::vector<std::shared_ptr<T>> &parcelableInfos, Parcel &data)
    {
        int32_t infoSize = 0;
        if (!data.ReadInt32(infoSize)) {
            ANS_LOGE("Failed to read Parcelable size.");
            return false;
        }
        infoSize = (infoSize < MAX_PARCELABLE_VECTOR_NUM) ? infoSize : MAX_PARCELABLE_VECTOR_NUM;
        parcelableInfos.clear();
        for (int32_t index = 0; index < infoSize; index++) {
            std::shared_ptr<T> info = std::shared_ptr<T>(data.ReadParcelable<T>());
            parcelableInfos.emplace_back(info);
        }

        return true;
    }

    static bool GetDataFromRawData(void *&buffer, size_t size, const void *data)
    {
        if (data == nullptr) {
            ANS_LOGE("GetData failed due to null data");
            return false;
        }
        if (size == 0 || size > NotificationConstant::MAX_IPC_RAW_DATA_SIZE) {
            ANS_LOGE("GetData failed due to zero size");
            return false;
        }
        buffer = malloc(size);
        if (buffer == nullptr) {
            ANS_LOGE("GetData failed due to malloc buffer failed");
            return false;
        }
        if (memcpy_s(buffer, size, data, size) != EOK) {
            free(buffer);
            ANS_LOGE("GetData failed due to memcpy_s failed");
            return false;
        }
        return true;
    }

    template<typename T>
    static bool WriteLargeInfoIntoParcelable(MessageParcel &data, const T &info, uint64_t maxSize)
    {
        Parcel tempParcel;
        tempParcel.SetMaxCapacity(maxSize);
        if (!tempParcel.WriteParcelable(&info)) {
            ANS_LOGE("Write info failed.");
            return false;
        }
        size_t infoSize = tempParcel.GetDataSize();
        if (infoSize > NotificationConstant::MAX_IPC_RAW_DATA_SIZE) {
            ANS_LOGE("data is too large, cannot write!");
            return false;
        }
        data.SetMaxCapacity(maxSize);
        if (!data.WriteUint32(static_cast<uint32_t>(infoSize))) {
            ANS_LOGE("write dataSize failed");
            return false;
        }
        if (!data.WriteRawData(reinterpret_cast<uint8_t *>(tempParcel.GetData()), infoSize)) {
            ANS_LOGE("write WriteRawData failed");
            return false;
        }
        return true;
    }

    template <typename T>
    static bool ReadLargeInfoFromParcelable(MessageParcel &data, T &info)
    {
        uint32_t dataSize = data.ReadUint32();
        if (dataSize > NotificationConstant::MAX_IPC_RAW_DATA_SIZE) {
            ANS_LOGE("data is too large, cannot read!");
            return false;
        }
        void *buffer = nullptr;
        if (!GetDataFromRawData(buffer, dataSize, data.ReadRawData(dataSize))) {
            ANS_LOGE("GetDataFromRawData failed dataSize : %{public}u", dataSize);
            return false;
        }
        MessageParcel tmpParcel;
        if (!tmpParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
            ANS_LOGE("GetDataFromRawData ParseFrom failed");
            free(buffer);
            return false;
        }
        std::unique_ptr<T> tempInfo(tmpParcel.ReadParcelable<T>());
        if (tempInfo == nullptr) {
            ANS_LOGE("Read info from parcel failed");
            return false;
        }
        info = *tempInfo;
        return true;
    }
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_CORE_IPC_COMMON_UTILS_H