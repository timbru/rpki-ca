package nl.bruijnzeels.tim.rpki.ca.ta

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command
import net.ripe.ipresource.IpResourceSet
import java.net.URI
import java.util.UUID
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload

sealed trait TaCommand extends Command {
  def id: UUID
}

case class TaCreate(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationUri: URI) extends TaCommand
case class TaPublish(id: UUID) extends TaCommand

//case class TaChildAdd(id: UUID, childId: UUID) extends TaCommand
//
//case class ResourceEntitlement(resourceClassName: String, entitledResources: IpResourceSet)
//case class TaChildSetResourceEntitlements(id: UUID, childId: UUID, entitlements: List[ResourceEntitlement]) extends TaCommand
//case class TaChildRequestResourceCertificate(id: UUID, childId: UUID, request: CertificateIssuanceRequestPayload) extends TaCommand
