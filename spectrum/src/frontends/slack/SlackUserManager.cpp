/**
 * libtransport -- C++ library for easy XMPP Transports development
 *
 * Copyright (C) 2011, Jan Kaluza <hanzz.k@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "SlackUserManager.h"
#include "SlackUserRegistration.h"
#include "SlackFrontend.h"
#include "SlackSession.h"
#include "SlackUser.h"

#include "transport/User.h"
#include "transport/Transport.h"
#include "transport/StorageBackend.h"
#include "transport/Logging.h"

#include <boost/algorithm/string.hpp>

namespace Transport {

DEFINE_LOGGER(logger, "SlackUserManager");

SlackUserManager::SlackUserManager(Component *component, UserRegistry *userRegistry, StorageBackend *storageBackend) : UserManager(component, userRegistry, storageBackend) {
	m_component = component;
	m_storageBackend = storageBackend;
    m_userRegistration = new SlackUserRegistration(component, this, storageBackend);

	onUserCreated.connect(boost::bind(&SlackUserManager::handleUserCreated, this, _1));
}

SlackUserManager::~SlackUserManager() {
    delete m_userRegistration;
}

void SlackUserManager::reconnectUser(const std::string &user) {
	UserInfo uinfo;
	if (!m_storageBackend->getUser(user, uinfo)) {
		LOG4CXX_ERROR(logger, "User " << user << " tried to reconnect, but he's not registered.");
		return;
	}

	LOG4CXX_INFO(logger, "Connecting user " << user << " to Slack network.");
	m_tempSessions[user] = new SlackSession(m_component, m_storageBackend, uinfo);
}

void SlackUserManager::sendVCard(unsigned int id, Swift::VCard::ref vcard) {

}

void SlackUserManager::sendMessage(boost::shared_ptr<Swift::Message> message) {
	User *user = getUser(message->getTo().toBare().toString());
	if (!user) {
		LOG4CXX_ERROR(logger, "Received message for unknown user " << message->getTo().toBare().toString());
		return;
	}

	static_cast<SlackUser *>(user)->getSession()->sendMessage(message);
}

SlackSession *SlackUserManager::moveTempSession(const std::string &user) {
	if (m_tempSessions.find(user) != m_tempSessions.end()) {
		SlackSession *session = m_tempSessions[user];
		m_tempSessions.erase(user);
		return session;
	}
	return NULL;
}

void SlackUserManager::moveTempSession(const std::string &user, SlackSession *session) {
	m_tempSessions[user] = session;
	session->setUser(NULL);
}


UserRegistration *SlackUserManager::getUserRegistration() {
	return m_userRegistration;
}

std::string SlackUserManager::handleOAuth2Code(const std::string &code, const std::string &state) {
	return static_cast<SlackUserRegistration *>(m_userRegistration)->handleOAuth2Code(code, state);
}

std::string SlackUserManager::getOAuth2URL(const std::vector<std::string> &args) {
	return static_cast<SlackUserRegistration *>(m_userRegistration)->createOAuth2URL(args);
}

void SlackUserManager::handleUserCreated(User *user) {
	LOG4CXX_INFO(logger, "handleUserCreated");
	static_cast<SlackUser *>(user)->getSession()->handleConnected();
}

bool SlackUserManager::handleAdminMessage(Swift::Message::ref message) {
	if (message->getBody().find("get_user_configuration") == 0) {
// 		std::string body = message->getBody();
// 		std::vector<std::string> args;
// 		boost::split(args, body, boost::is_any_of(" "));
// 		if (args.size() == 2) {
// 			UserInfo uinfo;
// 			if (!m_storageBackend->getUser(args[1], uinfo)) {
// 				message->setBody("Error: Unknown user");
// 				return true;
// 			}
// 
// 			std::string rooms = "";
// 			int type = (int) TYPE_STRING;
// 			m_storageBackend->getUserSetting(uinfo.id, "rooms", type, rooms);
// 
// 			m_storageBackend->getUserSetting(uinfo.id, "slack_channel", type, m_slackChannel);
// 		}
	}
	else if (message->getBody().find("join_room ") == 0) {
		std::string body = message->getBody();
		std::vector<std::string> args;
		boost::split(args, body, boost::is_any_of(" "));
		if (args.size() == 6) {
			UserInfo uinfo;
			if (!m_storageBackend->getUser(args[1], uinfo)) {
				message->setBody("Error: Unknown user");
				return true;
			}

			std::string rooms = "";
			int type = (int) TYPE_STRING;
			m_storageBackend->getUserSetting(uinfo.id, "rooms", type, rooms);
			rooms += message->getBody() + "\n";
			m_storageBackend->updateUserSetting(uinfo.id, "rooms", rooms);

			SlackUser *user = static_cast<SlackUser *>(getUser(args[1]));
			if (user) {
				user->getSession()->handleJoinMessage("", args, true);
			}
			message->setBody("Joined the room");
			return true;
		}
	}
	return false;
}


}
