package nl.bruijnzeels.tim.rpki.ca.rc

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import java.util.UUID

trait ResourceClassEvent extends Event {
  def resourceClassName: String
}

case class ResourceClassCreated(aggregateId: UUID, resourceClassName: String) extends ResourceClassEvent

