/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.util.UUID

import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event

sealed trait ProvisioningCommunicatorEvent extends Event

case class ProvisioningCommunicatorCreated(myIdentity: MyIdentity) extends ProvisioningCommunicatorEvent

case class ProvisioningCommunicatorAddedChild(childIdentity: ChildIdentity) extends ProvisioningCommunicatorEvent
case class ProvisioningCommunicatorPerformedChildExchange(exchange: ProvisioningChildExchange) extends ProvisioningCommunicatorEvent
case class ProvisioningChildExchange(childId: UUID, request: ProvisioningCmsObject, response: ProvisioningCmsObject)

case class ProvisioningCommunicatorAddedParent(parentIdentity: ParentIdentity) extends ProvisioningCommunicatorEvent
case class ProvisioningCommunicatorPerformedParentExchange(exchange: ProvisioningParentExchange) extends ProvisioningCommunicatorEvent
case class ProvisioningParentExchange(request: ProvisioningCmsObject, response: ProvisioningCmsObject)