/*
 * Implements XEP-0334: Message Processing Hints
 * Licensed under the Simplified BSD license.
 * See Documentation/Licenses/BSD-simplified.txt for more information.
 */

#pragma once

#include <Swiften/Serializer/GenericPayloadSerializer.h>
#include <Swiften/Elements/HintPayload.h>

namespace Swift {
	class HintPayloadSerializer : public GenericPayloadSerializer<HintPayload> {
	public:
		HintPayloadSerializer();

		virtual std::string serializePayload(std::shared_ptr<HintPayload>)  const;
	};
}
