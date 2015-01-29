package nl.bruijnzeels.tim.rpki.publication.server

import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Command
import nl.bruijnzeels.tim.rpki.publication.messages.PublicationProtocolMessage
import java.net.URI
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId

sealed trait PublicationServerCommand extends Command

case class PublicationServerCreate(aggregateId: UUID, rrdpBaseUri: URI) extends PublicationServerCommand {
  def versionedId = VersionedId(aggregateId)
}
case class PublicationServerPublish(versionedId: VersionedId, messages: List[PublicationProtocolMessage]) extends PublicationServerCommand