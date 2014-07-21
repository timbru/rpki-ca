package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta

case class TaCommandDispatcher() {

  def dispatch(command: TrustAnchorCommand) = {
    val existingTa = TrustAnchorStore.load(command.id)

    if (existingTa.isDefined && command.isInstanceOf[TrustAnchorCreate]) {
      throw new IllegalArgumentException("Can't create new TA with id " + command.id + ", TA with same id exists")
    }

    if (!existingTa.isDefined && !command.isInstanceOf[TrustAnchorCreate]) {
      throw new IllegalArgumentException("Can't find exisiting TA with id " + command.id + " for command")
    }

    val updatedTa = command match {
      case create: TrustAnchorCreate => TrustAnchorCreateCommandHandler.handle(create)
      case publish: TrustAnchorPublish => TrustAnchorPublishCommandHandler.handle(publish, existingTa.get)
      case addChild: TrustAnchorAddChild => TrustAnchorAddChildCommandHandler.handle(addChild, existingTa.get)
      case resourceListQuery: TrustAnchorProcessResourceListQuery => TrustAnchorProcessResourceListQueryCommandHandler.handle(resourceListQuery, existingTa.get)
    }

    TrustAnchorStore.save(updatedTa)
  }
}

object TrustAnchorCreateCommandHandler {
  def handle(command: TrustAnchorCreate) = TrustAnchor.create(command.id, command.name, command.taCertificateUri, command.publicationUri, command.resources)
}

trait TrustAnchorCommandHandler[C <: TrustAnchorCommand] {
  def handle(command: C, ta: TrustAnchor): TrustAnchor
}

object TrustAnchorPublishCommandHandler extends TrustAnchorCommandHandler[TrustAnchorPublish] {
  override def handle(command: TrustAnchorPublish, ta: TrustAnchor) = ta.publish()
}

object TrustAnchorAddChildCommandHandler extends TrustAnchorCommandHandler[TrustAnchorAddChild] {
  override def handle(command: TrustAnchorAddChild, ta: TrustAnchor) = ta.addChild(command.childId, command.childXml, command.childResources)
}

object TrustAnchorProcessResourceListQueryCommandHandler extends TrustAnchorCommandHandler[TrustAnchorProcessResourceListQuery] {
  override def handle(command: TrustAnchorProcessResourceListQuery, ta: TrustAnchor) = ta.processListQuery(command.childId, command.provisioningCmsObject)
}

