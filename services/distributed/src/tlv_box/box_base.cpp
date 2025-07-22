/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "box_base.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
const int32_t CURRENT_VERSION = 1000;
}
BoxBase::BoxBase()
{
    box_ = std::make_shared<TlvBox>();
    if (box_ == nullptr) {
        ANS_LOGW("Create tlv box failed.");
        return;
    }
}

BoxBase::BoxBase(std::shared_ptr<TlvBox> box)
{
    box_ = box;
}

unsigned char* BoxBase::GetByteBuffer()
{
    return box_->byteBuffer_;
}

uint32_t BoxBase::GetByteLength()
{
    return box_->bytesLength_;
}

bool BoxBase::Serialize()
{
    if (box_ == nullptr) {
        return false;
    }
    box_->PutValue(std::make_shared<TlvItem>(LOCAL_VERSION, CURRENT_VERSION));
    return box_->Serialize();
}
}
}
