/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "picture_option.h"

#include <new>

#include "ans_log_wrapper.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
PictureOption::PictureOption()
{}

PictureOption::PictureOption(const std::vector<std::string> &picList) : preparseLiveViewPicList_(picList)
{}

PictureOption::PictureOption(const PictureOption &option) : preparseLiveViewPicList_(option.preparseLiveViewPicList_)
{}

PictureOption::~PictureOption()
{}

void PictureOption::SetPreparseLiveViewPicList(const std::vector<std::string> &picList)
{
    preparseLiveViewPicList_ = picList;
}

std::vector<std::string> PictureOption::GetPreparseLiveViewPicList() const
{
    return preparseLiveViewPicList_;
}

bool PictureOption::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteStringVector(preparseLiveViewPicList_)) {
        ANS_LOGE("Failed to write preparseLiveViewPicList_");
        return false;
    }
    return true;
}

PictureOption *PictureOption::Unmarshalling(Parcel &parcel)
{
    PictureOption *option = new (std::nothrow) PictureOption();
    if (option && !option->ReadFromParcel(parcel)) {
        delete option;
        option = nullptr;
    }
    return option;
}

bool PictureOption::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadStringVector(&preparseLiveViewPicList_)) {
        ANS_LOGE("Failed to read preparseLiveViewPicList_");
        return false;
    }
    return true;
}

PictureOption& PictureOption::operator=(const PictureOption &option)
{
    if (this != &option) {
        preparseLiveViewPicList_ = option.preparseLiveViewPicList_;
    }
    return *this;
}
}  // namespace Notification
}  // namespace OHOS
